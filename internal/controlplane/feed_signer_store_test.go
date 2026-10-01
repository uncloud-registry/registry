package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// feedSignerTestHash derives a deterministic [32]byte request hash for tests.
func feedSignerTestHash(seed string) [32]byte {
	return sha256.Sum256([]byte("feed-signer-test:" + seed))
}

// testClaimToken returns a fresh claim token via the real entropy source,
// failing the test on an RNG error so callers stay concise.
func testClaimToken(t *testing.T) string {
	t.Helper()
	tok, err := newClaimToken()
	if err != nil {
		t.Fatalf("newClaimToken: %v", err)
	}
	return tok
}

// tableColumnsOf returns the set of column names on a table via PRAGMA.
func tableColumnsOf(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query(`pragma table_info(` + table + `)`)
	if err != nil {
		t.Fatalf("pragma table_info %s: %v", table, err)
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan pragma row: %v", err)
		}
		cols[name] = true
	}
	return cols
}

// sqliteObjectCount counts an object of a given type/name in sqlite_master.
func sqliteObjectCount(t *testing.T, db *sql.DB, typ, name string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`select count(*) from sqlite_master where type = ? and name = ?`, typ, name).Scan(&n); err != nil {
		t.Fatalf("count sqlite_master %s %s: %v", typ, name, err)
	}
	return n
}

// tableReferencesRegistry reports whether a table's FK graph references
// registries(id).
func tableReferencesRegistry(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	rows, err := db.Query(`pragma foreign_key_list(` + table + `)`)
	if err != nil {
		t.Fatalf("pragma foreign_key_list %s: %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, seq int
		var ftable, fcol, pcol, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &ftable, &fcol, &pcol, &onUpdate, &onDelete, &match); err != nil {
			t.Fatalf("scan fk row: %v", err)
		}
		if ftable == "registries" {
			return true
		}
	}
	return false
}

// seedFeedSignerRegistry creates a provisioned, READY registry with a
// deterministic canonical repo-state feed topic for signer/store tests.
func seedFeedSignerRegistry(t *testing.T, store *Store) (Registry, string) {
	t.Helper()
	owner := seedProvisioningOwner(t, store)
	reg, err := store.CreateProvisionedRegistry(context.Background(), Registry{
		Slug: "signertest", Host: "signer.registry.test", ENSName: "signer.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: testFeedOwner, DefaultStampBatchID: "batch-signer",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("seed provisioned registry: %v", err)
	}
	if err := store.MarkRegistryReady(context.Background(), reg.ID); err != nil {
		t.Fatalf("mark registry ready: %v", err)
	}
	topic := spec.RepoStateFeedRef(spec.NormalizeOwner(reg.FeedOwnerAddress), "myrepo")
	return reg, topic
}

// registerPublicationFence self-registers a trivial self-mapped
// publication_states row (attempt_id = operationID) satisfying migration 17's
// writer fence on feed_signer_operations, so these Store-level lifecycle
// tests can keep exercising Reserve/Claim/Release/Complete/Adopt directly, in
// isolation, exactly as they did before the fence existed.
func registerPublicationFence(t *testing.T, store *Store, operationID string, registryID int64) {
	t.Helper()
	if _, err := store.ReservePublicationExecution(context.Background(), operationID, registryID, operationID); err != nil {
		t.Fatalf("register publication fence for %s: %v", operationID, err)
	}
}

// TestMigration10ConstrainHardenedSchemaOnFresh proves a fresh database reaches
// version 10 with the hardened feed_signer_operations columns, the partial
// unique index, and the FK reference to registries.
func TestMigration10ConstrainHardenedSchemaOnFresh(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	v, err := CurrentSchemaVersion(ctx, db)
	if err != nil || v != 17 {
		t.Fatalf("expected schema version 17, got %d (err %v)", v, err)
	}
	cols := tableColumnsOf(t, db, "feed_signer_operations")
	for _, want := range []string{"operation_id", "registry_id", "topic", "request_hash", "state", "result_json", "claim_token", "lease_until", "attempts", "created_at", "updated_at"} {
		if !cols[want] {
			t.Fatalf("feed_signer_operations missing %q; got %v", want, cols)
		}
	}
	if sqliteObjectCount(t, db, "index", "feed_signer_active_repo_claim") != 1 {
		t.Fatal("expected partial unique index feed_signer_active_repo_claim")
	}
	if !tableReferencesRegistry(t, db, "feed_signer_operations") {
		t.Fatal("expected feed_signer_operations FK reference to registries")
	}
}

// TestMigration10EmptyUpgradeFromM9 applies migration 9 (the ORIGINAL m9
// schema, per the unchanged migration 9), confirms version 9, then upgrades
// through 10 and confirms the table is rebuilt to the hardening.
func TestMigration10EmptyUpgradeFromM9(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 9); err != nil {
		t.Fatalf("apply through 9: %v", err)
	}
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 9 {
		t.Fatalf("expected version 9, got %d (err %v)", v, err)
	}
	if tableColumnsOf(t, db, "feed_signer_operations")["registry_id"] {
		t.Fatal("migration-9 table must NOT already carry registry_id")
	}
	if err := applyMigrationsThrough(ctx, db, 10); err != nil {
		t.Fatalf("upgrade through 10 on empty m9: %v", err)
	}
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 10 {
		t.Fatalf("expected version 10, got %d (err %v)", v, err)
	}
	if !tableColumnsOf(t, db, "feed_signer_operations")["registry_id"] {
		t.Fatal("migration-10 table must carry registry_id")
	}
}

// TestMigration10PreservesM9RowsInQuarantine proves migration 10 does NOT strand
// migration-9 rows and does NOT fabricate their missing registry_id/topic:
// every m9 row is preserved BYTE-FOR-BYTE in the constrained
// feed_signer_operations_legacy quarantine table, the hardened ACTIVE table is
// created empty, and the upgrade reaches the LATEST version (11) with the
// quarantine still intact.
func TestMigration10PreservesM9RowsInQuarantine(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 9); err != nil {
		t.Fatalf("apply through 9: %v", err)
	}
	legacyHash := feedSignerTestHash("legacy")
	legacyResult := `{"operationID":"m9-legacy-op","feed":"feed://` + strings.Repeat("ab", 20) + `/` + strings.Repeat("cd", 32) + `","reference":"` + strings.Repeat("ef", 32) + `"}`
	nowNs := timeToNanos(time.Now().UTC())
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, request_hash, state, result_json, created_at, updated_at)
		values (?, ?, 'succeeded', ?, ?, ?)`, "m9-legacy-op", legacyHash[:], legacyResult, nowNs, nowNs); err != nil {
		t.Fatalf("seed m9 row: %v", err)
	}
	if err := applyMigrationsThrough(ctx, db, 11); err != nil {
		t.Fatalf("upgrade through 11 over non-empty m9: %v", err)
	}
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 11 {
		t.Fatalf("expected version 11, got %d (err %v)", v, err)
	}
	// The hardened ACTIVE table must exist and be EMPTY (an m9 row cannot be
	// carried forward without inventing registry_id/topic).
	if !tableColumnsOf(t, db, "feed_signer_operations")["registry_id"] {
		t.Fatal("migration-10 table must carry registry_id")
	}
	var activeCount int
	if err := db.QueryRowContext(ctx, `select count(*) from feed_signer_operations`).Scan(&activeCount); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if activeCount != 0 {
		t.Fatalf("expected empty active table after quarantine, got %d rows", activeCount)
	}
	// The m9 row is preserved BYTE-FOR-BYTE in quarantine.
	var (
		gotHash            []byte
		gotState, gotRes   string
		gotCreated, gotUpd int64
	)
	if err := db.QueryRowContext(ctx, `select request_hash, state, result_json, created_at, updated_at
		from feed_signer_operations_legacy where operation_id = 'm9-legacy-op'`).
		Scan(&gotHash, &gotState, &gotRes, &gotCreated, &gotUpd); err != nil {
		t.Fatalf("read quarantine row: %v", err)
	}
	var gotHashArr [32]byte
	copy(gotHashArr[:], gotHash)
	if gotHashArr != legacyHash || gotState != "succeeded" || gotRes != legacyResult ||
		gotCreated != nowNs || gotUpd != nowNs {
		t.Fatalf("quarantine row not preserved byte-for-byte: hash=%x state=%q result=%q created=%d upd=%d",
			gotHashArr, gotState, gotRes, gotCreated, gotUpd)
	}
}

// TestMigration11HardensOldV10ActiveRows simulates a database ALREADY stamped
// with the OLD migration-10 schema (hardened active table, but WITHOUT the
// quarantine table, and WITHOUT the result-integrity triggers), carrying a
// VALID succeeded active row. Migration 11 must re-created the quarantine
// table, install both triggers, and preserve the valid state/result exactly.
func TestMigration11HardensOldV10ActiveRows(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 10); err != nil {
		t.Fatalf("apply through 10: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	// Drop the quarantine table and any triggers to reproduce the OLD-m10
	// physical state, then seed a VALID succeeded active row.
	if _, err := db.ExecContext(ctx, `drop table feed_signer_operations_legacy`); err != nil {
		t.Fatalf("drop quarantine to simulate old v10: %v", err)
	}
	if _, err := db.ExecContext(ctx, `drop trigger if exists feed_signer_result_integrity_ins`); err != nil {
		t.Fatalf("drop ins trigger: %v", err)
	}
	if _, err := db.ExecContext(ctx, `drop trigger if exists feed_signer_result_integrity_upd`); err != nil {
		t.Fatalf("drop upd trigger: %v", err)
	}
	reqHash := feedSignerTestHash("old-v10")
	validResult := `{"operationID":"old-v10-op","feed":"` + topic + `","reference":"` + strings.Repeat("ab", 32) + `"}`
	nowNs := timeToNanos(time.Now().UTC())
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values ('old-v10-op', ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
		reg.ID, topic, reqHash[:], validResult, nowNs, nowNs); err != nil {
		t.Fatalf("seed valid old-v10 active row: %v", err)
	}

	// Apply migrations: 11 (harden old-v10) and 12 (correct canonical triggers)
	// both run (already at 10) and must succeed for a valid row. Migration 16
	// (round 4 / Finding 1) then fails closed atomically: this seeded row is a
	// genuine pre-v16 'succeeded' feed_signer_operations row with no
	// publication_states equivalent, exactly the unsafe history that
	// migration cannot reconstruct — so the full chain must refuse there,
	// leaving version 15 current and the migration-11/12 hardening (below)
	// fully applied and preserved.
	if err := ApplyMigrations(ctx, db); err == nil || !errors.Is(err, errPublicationStateHistoryUnsafe) {
		t.Fatalf("migration 16 must refuse pre-v16 succeeded history seeded for the migration-11/12 hardening proof, got %v", err)
	}
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 15 {
		t.Fatalf("expected version 15 (migration 16 refused), got %d (err %v)", v, err)
	}
	// Quarantine table re-created, triggers installed, valid row preserved.
	if sqliteObjectCount(t, db, "table", "feed_signer_operations_legacy") != 1 {
		t.Fatal("migration 11 must re-create the quarantine table for old-v10 databases")
	}
	if sqliteObjectCount(t, db, "trigger", "feed_signer_result_integrity_ins") != 1 ||
		sqliteObjectCount(t, db, "trigger", "feed_signer_result_integrity_upd") != 1 {
		t.Fatal("migration 11 must install both result-integrity triggers")
	}
	var (
		gotState string
		gotRes   []byte
	)
	if err := db.QueryRowContext(ctx, `select state, result_json from feed_signer_operations
		where operation_id='old-v10-op'`).Scan(&gotState, &gotRes); err != nil {
		t.Fatalf("read hardened old-v10 row: %v", err)
	}
	if gotState != "succeeded" || string(gotRes) != validResult {
		t.Fatalf("valid old-v10 row not preserved: state=%q result=%s", gotState, gotRes)
	}
}

// TestMigration11RollsBackOnMalformedOldV10 simulates an old-m10 database whose
// active table carries a MALFORMED succeeded result (passes the loose v10 CHECK
// but violates the v11 canonical contract). Migration 11 must fail ATOMICALLY:
// version stays 10, every row and the schema are byte-identical, nothing is
// altered.
func TestMigration11RollsBackOnMalformedOldV10(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 10); err != nil {
		t.Fatalf("apply through 10: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	if _, err := db.ExecContext(ctx, `drop trigger if exists feed_signer_result_integrity_ins`); err != nil {
		t.Fatalf("drop ins trigger: %v", err)
	}
	if _, err := db.ExecContext(ctx, `drop trigger if exists feed_signer_result_integrity_upd`); err != nil {
		t.Fatalf("drop upd trigger: %v", err)
	}
	// A malformed succeeded result: canonical-looking object but the reference
	// is not 64 lowercase hex, so the v11 trigger must reject it.
	reqHash := feedSignerTestHash("old-v10-bad")
	badResult := `{"operationID":"old-v10-bad","feed":"` + topic + `","reference":"ZZ"}` // < 64 hex, not lowercase
	nowNs := timeToNanos(time.Now().UTC())
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values ('old-v10-bad', ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
		reg.ID, topic, reqHash[:], badResult, nowNs, nowNs); err != nil {
		t.Fatalf("seed malformed old-v10 row (must pass loose v10 CHECK): %v", err)
	}

	if err := ApplyMigrations(ctx, db); err == nil {
		t.Fatal("migration 11 must fail when hardening encounters a malformed old-v10 row")
	}
	// Version stays 10 and the row is byte-identical (rollback was total).
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 10 {
		t.Fatalf("version must stay 10 on malformed upgrade, got %d (err %v)", v, err)
	}
	var (
		gotState string
		gotRes   []byte
	)
	if err := db.QueryRowContext(ctx, `select state, result_json from feed_signer_operations
		where operation_id='old-v10-bad'`).Scan(&gotState, &gotRes); err != nil {
		t.Fatalf("read malformed row after rollback: %v", err)
	}
	if gotState != "succeeded" || string(gotRes) != badResult {
		t.Fatalf("malformed row must be byte-identical after rollback: state=%q result=%s", gotState, gotRes)
	}
	// The quarantine table and triggers must NOT have survived the rollback.
	if sqliteObjectCount(t, db, "trigger", "feed_signer_result_integrity_ins") != 0 {
		t.Fatal("rollback must not leave the result-integrity trigger installed")
	}
}
func TestFeedSignerOperationReserveClaimCompleteLifecycle(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	reqHash := feedSignerTestHash("lifecycle")

	registerPublicationFence(t, store, "op-lifecycle", reg.ID)
	op, err := store.ReserveFeedSignerOperation(ctx, "op-lifecycle", reg.ID, topic, reqHash)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if op.State != FeedSignerOpPending || op.RegistryID != reg.ID || op.Topic != topic ||
		op.ResultJSON != nil || op.ClaimToken != nil || op.LeaseUntil != nil {
		t.Fatalf("pending operation malformed after reserve: %+v", op)
	}

	token := testClaimToken(t)
	won, err := store.ClaimFeedSignerOperation(ctx, "op-lifecycle", reqHash, token, time.Now().UTC().Add(time.Hour))
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	op, _ = store.GetFeedSignerOperation(ctx, "op-lifecycle")
	if op.State != FeedSignerOpProcessing || op.ClaimToken == nil || *op.ClaimToken != token ||
		op.LeaseUntil == nil || op.Attempts != 1 {
		t.Fatalf("processing operation malformed after claim: %+v", op)
	}

	resultJSON := []byte(`{"operationID":"op-lifecycle","feed":"` + topic + `","reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := store.CompleteFeedSignerOperation(ctx, "op-lifecycle", reqHash, token, resultJSON); err != nil {
		t.Fatalf("complete: %v", err)
	}
	op, _ = store.GetFeedSignerOperation(ctx, "op-lifecycle")
	if op.State != FeedSignerOpSucceeded || op.ClaimToken != nil || op.LeaseUntil != nil {
		t.Fatalf("succeeded operation must be claim-free: %+v", op)
	}
	if string(op.ResultJSON) != string(resultJSON) {
		t.Fatalf("stored result mismatch: %s", op.ResultJSON)
	}
}

// TestFeedSignerOperationReleaseReturnsToPendingAndReleaseRequiresToken proves
// the definite-failure release path: release clears the claim back to pending
// with a matching token, and a WRONG/stale token cannot release.
func TestFeedSignerOperationReleaseRequiresToken(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	reqHash := feedSignerTestHash("release")
	registerPublicationFence(t, store, "op-release", reg.ID)
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-release", reg.ID, topic, reqHash); err != nil {
		t.Fatal(err)
	}
	token := testClaimToken(t)
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-release", reqHash, token, time.Now().UTC().Add(time.Hour)); err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	// A wrong token must NOT release the claim.
	if err := store.ReleaseFeedSignerOperation(ctx, "op-release", "stale-token"); err != nil {
		t.Fatalf("wrong-token release: %v", err)
	}
	op, _ := store.GetFeedSignerOperation(ctx, "op-release")
	if op.State != FeedSignerOpProcessing || op.ClaimToken == nil {
		t.Fatal("wrong token must not have released the claim")
	}
	// The correct token releases it to pending, claim-free.
	if err := store.ReleaseFeedSignerOperation(ctx, "op-release", token); err != nil {
		t.Fatalf("release: %v", err)
	}
	op, _ = store.GetFeedSignerOperation(ctx, "op-release")
	if op.State != FeedSignerOpPending || op.ClaimToken != nil || op.LeaseUntil != nil {
		t.Fatalf("released operation must be claim-free pending: %+v", op)
	}
}

// TestFeedSignerOperationExpiredLeaseTakeover proves a crashed attempt's
// expired lease is re-claimed with a fresh token, attempts increment, and the
// OLD token can no longer complete the operation.
func TestFeedSignerOperationExpiredLeaseTakeover(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	reqHash := feedSignerTestHash("takeover")
	registerPublicationFence(t, store, "op-takeover", reg.ID)
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-takeover", reg.ID, topic, reqHash); err != nil {
		t.Fatal(err)
	}
	oldToken := testClaimToken(t)
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-takeover", reqHash, oldToken, time.Now().UTC().Add(-10*time.Minute)); err != nil || !won {
		t.Fatalf("initial claim: won=%v err=%v", won, err)
	}
	newToken := testClaimToken(t)
	won, err := store.ClaimFeedSignerOperation(ctx, "op-takeover", reqHash, newToken, time.Now().UTC().Add(time.Hour))
	if err != nil || !won {
		t.Fatalf("takeover claim: won=%v err=%v", won, err)
	}
	op, _ := store.GetFeedSignerOperation(ctx, "op-takeover")
	if op.ClaimToken == nil || *op.ClaimToken != newToken || op.Attempts != 2 {
		t.Fatalf("takeover state wrong: attempts=%d token=%v", op.Attempts, op.ClaimToken)
	}
	// The OLD token must neither complete nor release the new owner's claim.
	if err := store.CompleteFeedSignerOperation(ctx, "op-takeover", reqHash, oldToken, []byte(`{}`)); err == nil {
		t.Fatal("stale token must fail to complete")
	}
	if err := store.ReleaseFeedSignerOperation(ctx, "op-takeover", oldToken); err != nil {
		t.Fatalf("stale token release must be a harmless no-op: %v", err)
	}
	op, _ = store.GetFeedSignerOperation(ctx, "op-takeover")
	if op.ClaimToken == nil || *op.ClaimToken != newToken {
		t.Fatal("stale token must not have released the new owner's claim")
	}
	// The current owner CAN complete with its exact token.
	canonical := []byte(`{"operationID":"op-takeover","feed":"` + topic + `","reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := store.CompleteFeedSignerOperation(ctx, "op-takeover", reqHash, newToken, canonical); err != nil {
		t.Fatalf("current-owner complete failed: %v", err)
	}
}

// TestFeedSignerOperationDistinctOpsShareActiveRepoClaimGate proves the partial
// unique index at the STORE level: a distinct operation ID targeting the same
// registry+topic cannot hold the processing claim alongside another. The loser
// gets an error (never an update); once the winner completes and frees the
// repository slot, the loser can claim.
func TestFeedSignerOperationDistinctOpsShareActiveRepoClaimGate(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	hashA := feedSignerTestHash("A")
	hashB := feedSignerTestHash("B")
	registerPublicationFence(t, store, "op-A", reg.ID)
	registerPublicationFence(t, store, "op-B", reg.ID)
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-A", reg.ID, topic, hashA); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-B", reg.ID, topic, hashB); err != nil {
		t.Fatal(err)
	}
	tokenA := testClaimToken(t)
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-A", hashA, tokenA, time.Now().UTC().Add(time.Hour)); err != nil || !won {
		t.Fatalf("claim op-A: won=%v err=%v", won, err)
	}
	// op-B on the SAME registry+topic cannot claim while op-A holds the slot.
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-B", hashB, testClaimToken(t), time.Now().UTC().Add(time.Hour)); err == nil && won {
		t.Fatal("expected distinct-op claim on the same repo feed to be refused")
	}
	// op-A completes and frees the slot.
	resultA := []byte(`{"operationID":"op-A","feed":"` + topic + `","reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := store.CompleteFeedSignerOperation(ctx, "op-A", hashA, tokenA, resultA); err != nil {
		t.Fatalf("complete op-A: %v", err)
	}
	// op-B can now claim and complete.
	tokenB := testClaimToken(t)
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-B", hashB, tokenB, time.Now().UTC().Add(time.Hour)); err != nil || !won {
		t.Fatalf("claim op-B after slot freed: won=%v err=%v", won, err)
	}
	resultB := []byte(`{"operationID":"op-B","feed":"` + topic + `","reference":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
	if err := store.CompleteFeedSignerOperation(ctx, "op-B", hashB, tokenB, resultB); err != nil {
		t.Fatalf("complete op-B: %v", err)
	}
}

// TestFeedSignerOperationCompleteIdempotentOnConcurrentSuccess proves the
// zero-row concurrent-success path: completing an ALREADY-succeeded operation
// with IDENTICAL canonical bytes is an idempotent no-op, while DIFFERING bytes
// with the same hash fail (canonical byte compare, not just hash).
func TestFeedSignerOperationCompleteIdempotentOnConcurrentSuccess(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	reqHash := feedSignerTestHash("idem")
	registerPublicationFence(t, store, "op-idem", reg.ID)
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-idem", reg.ID, topic, reqHash); err != nil {
		t.Fatal(err)
	}
	token := testClaimToken(t)
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-idem", reqHash, token, time.Now().UTC().Add(time.Hour)); err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	resultJSON := []byte(`{"operationID":"op-idem","feed":"` + topic + `","reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := store.CompleteFeedSignerOperation(ctx, "op-idem", reqHash, token, resultJSON); err != nil {
		t.Fatalf("first complete: %v", err)
	}
	if err := store.CompleteFeedSignerOperation(ctx, "op-idem", reqHash, token, resultJSON); err != nil {
		t.Fatalf("idempotent re-complete with identical canonical bytes: %v", err)
	}
	differing := []byte(`{"operationID":"op-idem","feed":"` + topic + `","reference":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
	if err := store.CompleteFeedSignerOperation(ctx, "op-idem", reqHash, token, differing); err == nil {
		t.Fatal("expected complete with differing canonical bytes to fail against an already-succeeded row")
	}
}

// TestFeedSignerOperationAdversarialCoherence drives direct SQL against the
// hardened CHECK constraints: a succeeded result must be an exact bounded
// object carrying all three fields, pending/processing refuse any result, and
// processing requires a claim.
func TestFeedSignerOperationAdversarialCoherence(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	nowNs := timeToNanos(time.Now().UTC())
	sqlPrefix := `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at) values `
	validResult := `{"operationID":"op-adv","feed":"` + topic + `","reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`

	cases := []struct {
		name  string
		query string
	}{
		{
			name:  "succeeded-without-result",
			query: `('op-adv-1', ?, ?, ?, 'succeeded', null, null, null, 0, ?, ?)`,
		},
		{
			name:  "succeeded-invalid-result-not-object",
			query: `('op-adv-2', ?, ?, ?, 'succeeded', '123', null, null, 0, ?, ?)`,
		},
		{
			name:  "succeeded-result-missing-feed-field",
			query: `('op-adv-3', ?, ?, ?, 'succeeded', '{"operationID":"op-adv-3","reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}', null, null, 0, ?, ?)`,
		},
		{
			name:  "pending-with-result",
			query: `('op-adv-4', ?, ?, ?, 'pending', '` + validResult + `', null, null, 0, ?, ?)`,
		},
		{
			name:  "processing-without-claim",
			query: `('op-adv-5', ?, ?, ?, 'processing', null, null, null, 0, ?, ?)`,
		},
		{
			name:  "processing-claim-token-without-lease",
			query: `('op-adv-6', ?, ?, ?, 'processing', null, 'tok', null, 0, ?, ?)`,
		},
		{
			name:  "unknown-state",
			query: `('op-adv-7', ?, ?, ?, 'bogus', null, null, null, 0, ?, ?)`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hash [32]byte
			copy(hash[:], []byte(tc.name))
			_, err := store.DB.ExecContext(ctx, sqlPrefix+tc.query,
				reg.ID, topic, hash[:], nowNs, nowNs)
			if err == nil {
				t.Fatalf("expected CHECK violation for %s, got nil", tc.name)
			}
		})
	}

	// A well-formed direct-SQL succeeded row is accepted, proving the coherence
	// is EXACT, not over-restrictive. The contract requires operationID to equal
	// the row's operation_id, so the good fixture is built for the exact row id.
	// This is the ONLY row in this test seeded with a matching publication_states
	// fence: every malformed case above deliberately stays unfenced so its
	// rejection continues to prove the CHECK-constraint boundary, not the fence.
	goodHash := feedSignerTestHash("good")
	goodResult := `{"operationID":"op-adv-good","feed":"` + topic + `","reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	registerPublicationFence(t, store, "op-adv-good", reg.ID)
	if _, err := store.DB.ExecContext(ctx, sqlPrefix+
		`('op-adv-good', ?, ?, ?, 'succeeded', '`+goodResult+`', null, null, 0, ?, ?)`,
		reg.ID, topic, goodHash[:], nowNs, nowNs); err != nil {
		t.Fatalf("well-formed succeeded row rejected: %v", err)
	}

	// An extra field is allowed by SQL but rejected by the strict Go decoder
	// (which is covered by the signer strict-decode tests).
}

// TestFeedSignerOperationStarvationExpiredDistinctRowCleared proves the
// anti-starvation behavior: an EXPIRED processing row for a DIFFERENT
// operation on the SAME registry+topic (a crashed owner) is atomically
// released back to pending inside the claim transaction, so a distinct
// operation can claim the repository feed's idle slot instead of being starved
// across stores/processes. A LIVE distinct lease is never touched (the partial
// unique index survives that case).
func TestFeedSignerOperationStarvationExpiredDistinctRowCleared(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	hashA := feedSignerTestHash("starve-A")
	hashB := feedSignerTestHash("starve-B")
	registerPublicationFence(t, store, "op-A", reg.ID)
	registerPublicationFence(t, store, "op-B", reg.ID)
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-A", reg.ID, topic, hashA); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-B", reg.ID, topic, hashB); err != nil {
		t.Fatal(err)
	}
	// A crashed owner of op-A left an EXPIRED processing claim on the shared
	// (registry, topic) slot.
	tokenA := testClaimToken(t)
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-A", hashA, tokenA, time.Now().UTC().Add(-time.Minute)); err != nil || !won {
		t.Fatalf("claim op-A: won=%v err=%v", won, err)
	}
	// op-B, a DISTINCT operation on the same feed, must NOT be starved: the
	// claim transaction atomically clears op-A's expired processing claim and
	// lets op-B take the idle slot.
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-B", hashB, testClaimToken(t), time.Now().UTC().Add(time.Hour)); err != nil || !won {
		t.Fatalf("distinct op-B claim must clear expired op-A and win: won=%v err=%v", won, err)
	}
	opA, _ := store.GetFeedSignerOperation(ctx, "op-A")
	if opA.State != FeedSignerOpPending || opA.ClaimToken != nil || opA.LeaseUntil != nil {
		t.Fatalf("expired distinct op-A claim must have been cleared back to pending: %+v", opA)
	}
	opB, _ := store.GetFeedSignerOperation(ctx, "op-B")
	if opB.State != FeedSignerOpProcessing || opB.ClaimToken == nil {
		t.Fatalf("distinct op-B must be processing: %+v", opB)
	}
}

// TestFeedSignerOperationStarvationKeepsLiveDistinctLease proves the
// anti-starvation path NEVER evicts a LIVE owner: when a distinct operation
// holds a current lease on the shared (registry, topic) slot, another claim
// must fail (lost claim), not clear the live lease.
func TestFeedSignerOperationStarvationKeepsLiveDistinctLease(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	hashA := feedSignerTestHash("live-A")
	hashB := feedSignerTestHash("live-B")
	registerPublicationFence(t, store, "op-A", reg.ID)
	registerPublicationFence(t, store, "op-B", reg.ID)
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-A", reg.ID, topic, hashA); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-B", reg.ID, topic, hashB); err != nil {
		t.Fatal(err)
	}
	tokenA := testClaimToken(t)
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-A", hashA, tokenA, time.Now().UTC().Add(time.Hour)); err != nil || !won {
		t.Fatalf("claim op-A: won=%v err=%v", won, err)
	}
	// A LIVE distinct lease must block op-B (partial unique index), NOT be
	// cleared by the anti-starvation release (which is conditional on expiry).
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-B", hashB, testClaimToken(t), time.Now().UTC().Add(time.Hour)); err == nil && won {
		t.Fatal("distinct op-B must NOT claim while op-A's lease is live")
	}
	opA, _ := store.GetFeedSignerOperation(ctx, "op-A")
	if opA.State != FeedSignerOpProcessing || opA.ClaimToken == nil || opA.LeaseUntil == nil {
		t.Fatalf("live op-A lease must be preserved: %+v", opA)
	}
}

// TestFeedSignerLeaseExtensionRejectsStaleToken proves the joined renewal
// heartbeat is token-owned: a STALE token (already taken over) cannot extend
// the lease, and ownership re-check fails closed BEFORE the external update.
func TestFeedSignerLeaseExtensionRejectsStaleToken(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	reqHash := feedSignerTestHash("lease-stale")
	registerPublicationFence(t, store, "op-lease", reg.ID)
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-lease", reg.ID, topic, reqHash); err != nil {
		t.Fatal(err)
	}
	oldToken := testClaimToken(t)
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-lease", reqHash, oldToken, time.Now().UTC().Add(-5*time.Minute)); err != nil || !won {
		t.Fatalf("initial claim: won=%v err=%v", won, err)
	}
	// Take the lease over with a new token.
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-lease", reqHash, testClaimToken(t), time.Now().UTC().Add(time.Hour)); err != nil || !won {
		t.Fatalf("takeover claim: won=%v err=%v", won, err)
	}
	// The stale (old) token must be unable to extend the lease.
	if err := store.ExtendFeedSignerLease(ctx, "op-lease", oldToken, time.Now().UTC().Add(time.Hour)); err == nil {
		t.Fatal("stale token must fail to extend the lease")
	}
	// A current-owner extension succeeds.
	op, _ := store.GetFeedSignerOperation(ctx, "op-lease")
	if err := store.ExtendFeedSignerLease(ctx, "op-lease", *op.ClaimToken, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("current-owner extension failed: %v", err)
	}
	// Ownership re-check: stale token fails closed, current token passes.
	if err := store.EnsureFeedSignerLeaseOwned(ctx, "op-lease", oldToken); err == nil {
		t.Fatal("stale token must fail ownership re-check")
	}
	if err := store.EnsureFeedSignerLeaseOwned(ctx, "op-lease", *op.ClaimToken); err != nil {
		t.Fatalf("current token must pass ownership re-check: %v", err)
	}
}

// TestAdoptLegacyFeedSignerOperation drives the migration-9 quarantine adoption
// gate across BOTH identities that can key a quarantine row:
//
//   - CURRENT identity: a row keyed by the current operation ID must carry the
//     CURRENT canonical request hash (reqHash) to be promoted;
//   - HISTORICAL identity: a row keyed by the DERIVED historical migration-9
//     operation ID (where old and new IDs DIFFER, the normal m9 case) must
//     carry the exact historical request hash (legacyFeedCommitHashFor) to be
//     validated.
//
// A pending row becomes an active pending row carrying the supplied
// registry_id/canonical topic under the CURRENT operation ID; a succeeded row
// is strictly decoded and promoted under the CURRENT operation ID with the
// result REWRITTEN to the current operation ID (feed/reference unchanged); a
// differing hash under either identity is a CONFLICT; a malformed legacy
// succeeded result FAILS CLOSED; and TWO distinct valid candidates are an
// AMBIGUITY that fails closed. A real m9 row keyed by the historical ID with an
// m9 hash — which the round-3 code (hash over the CURRENT request with the
// CURRENT op ID) missed — must now adopt.
func TestAdoptLegacyFeedSignerOperation(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	ref := strings.Repeat("ab", 32)
	nowNs := timeToNanos(time.Now().UTC())
	seed := func(opID, state, result string, hash [32]byte) {
		t.Helper()
		if _, err := store.DB.ExecContext(ctx, `insert into feed_signer_operations_legacy
			(operation_id, request_hash, state, result_json, created_at, updated_at)
			values (?, ?, ?, ?, ?, ?)`, opID, hash[:], state, sql.NullString{String: result, Valid: state == "succeeded"}, nowNs, nowNs); err != nil {
			t.Fatalf("seed legacy %s: %v", opID, err)
		}
	}

	// A concrete current request and its reconstructed historical twin (old and
	// new operation IDs DIFFER — the normal case).
	req := publish.FeedCommitRequest{
		OperationID:        "current-op-1",
		RegistryID:         reg.ID,
		Owner:              "0x" + testFeedOwner,
		Topic:              topic,
		Reference:          ref,
		BatchID:            "batch-1",
		ExpectedGeneration: 4,
	}
	reqHash := NormalizeFeedCommitHash(req)
	// The DERIVED historical operation ID for the same logical publication, and
	// the exact historical request hash over the reconstructed historical
	// request (OperationID := the historical value).
	histID := legacyComputeOperationID(reg.ID, req.Owner, "repo1", "latest", "sha256:"+strings.Repeat("a", 64), req.ExpectedGeneration)
	if histID == req.OperationID {
		t.Fatal("test requires the historical and current operation IDs to differ")
	}
	histHash := legacyFeedCommitHashFor(histID, req)
	histReq := req
	histReq.OperationID = histID
	if histHash != m9HistoricalRequestHash(histReq) {
		t.Fatal("legacyFeedCommitHashFor must equal the independently-pinned m9 hash over the reconstructed historical request")
	}

	// 1. PENDING CURRENT identity -> active pending under current ID + reqHash.
	seed("current-pending", "pending", "", reqHash)
	registerPublicationFence(t, store, "current-pending", reg.ID)
	topicOther := spec.RepoStateFeedRef(testFeedOwner, "otherrepo")
	if adopted, err := store.AdoptLegacyFeedSignerOperation(ctx, "current-pending", reg.ID, topicOther, ref, reqHash, nil); err != nil || !adopted {
		t.Fatalf("current pending adoption: adopted=%v err=%v", adopted, err)
	}
	if op, err := store.GetFeedSignerOperation(ctx, "current-pending"); err != nil || op.State != FeedSignerOpPending || op.RegistryID != reg.ID || op.Topic != topicOther || op.RequestHash != reqHash {
		t.Fatalf("adopted current pending row malformed: %+v err=%v", op, err)
	}
	if n := legacyCount(t, store, "current-pending"); n != 0 {
		t.Fatalf("current pending quarantine row must be deleted, got %d", n)
	}

	// 2. PENDING HISTORICAL identity (keyed by histID, m9 hash) -> active
	//    pending under CURRENT ID; quarantine deleted.
	seed(histID, "pending", "", histHash)
	registerPublicationFence(t, store, req.OperationID, reg.ID)
	if adopted, err := store.AdoptLegacyFeedSignerOperation(ctx, req.OperationID, reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{{OperationID: histID, RequestHash: histHash}}); err != nil || !adopted {
		t.Fatalf("historical pending adoption: adopted=%v err=%v", adopted, err)
	}
	op, err := store.GetFeedSignerOperation(ctx, req.OperationID)
	if err != nil || op.State != FeedSignerOpPending || op.RegistryID != reg.ID || op.Topic != topic || op.RequestHash != reqHash {
		t.Fatalf("historical-pending adopted active row malformed: %+v err=%v", op, err)
	}
	if n := legacyCount(t, store, histID); n != 0 {
		t.Fatalf("historical pending quarantine row must be deleted, got %d", n)
	}

	// 3. SUCCEEDED CURRENT identity -> adopted with current result.
	goodCurrent := `{"operationID":"suc-current","feed":"` + topic + `","reference":"` + ref + `"}`
	seed("suc-current", "succeeded", goodCurrent, reqHash)
	registerPublicationFence(t, store, "suc-current", reg.ID)
	if adopted, err := store.AdoptLegacyFeedSignerOperation(ctx, "suc-current", reg.ID, topic, ref, reqHash, nil); err != nil || !adopted {
		t.Fatalf("current succeeded adoption: adopted=%v err=%v", adopted, err)
	}
	if op, err := store.GetFeedSignerOperation(ctx, "suc-current"); err != nil || op.State != FeedSignerOpSucceeded || string(op.ResultJSON) != goodCurrent {
		t.Fatalf("adopted current succeeded row malformed: state=%q result=%s err=%v", op.State, op.ResultJSON, err)
	}

	// 4. SUCCEEDED HISTORICAL identity: m9 result carried the HISTORICAL
	//    OperationID; it is validated against the LEGACY row identity and
	//    promoted with the result REWRITTEN to the CURRENT operation ID, feed/
	//    reference unchanged. A DISTINCT current operation ID is used so this
	//    step never collides with the active row promoted in step 2.
	req2 := req
	req2.OperationID = "current-op-2"
	req2Hash := NormalizeFeedCommitHash(req2)
	histID2 := legacyComputeOperationID(reg.ID, req2.Owner, "repo1", "latest", "sha256:"+strings.Repeat("d", 64), req2.ExpectedGeneration)
	if histID2 == req2.OperationID || histID2 == histID {
		t.Fatal("test requires distinct historical operation IDs")
	}
	histHash2 := legacyFeedCommitHashFor(histID2, req2)
	histResult := `{"operationID":"` + histID2 + `","feed":"` + topic + `","reference":"` + ref + `"}`
	seed(histID2, "succeeded", histResult, histHash2)
	registerPublicationFence(t, store, req2.OperationID, reg.ID)
	if adopted, err := store.AdoptLegacyFeedSignerOperation(ctx, req2.OperationID, reg.ID, topic, ref, req2Hash, []LegacyOperationCandidate{{OperationID: histID2, RequestHash: histHash2}}); err != nil || !adopted {
		t.Fatalf("historical succeeded adoption: adopted=%v err=%v", adopted, err)
	}
	op, err = store.GetFeedSignerOperation(ctx, req2.OperationID)
	if err != nil || op.State != FeedSignerOpSucceeded {
		t.Fatalf("historical-succeeded active row malformed: state=%q err=%v", op.State, err)
	}
	wantRewritten := `{"operationID":` + strconv.Quote(req2.OperationID) + `,"feed":"` + topic + `","reference":"` + ref + `"}`
	if string(op.ResultJSON) != wantRewritten {
		t.Fatalf("historical-succeeded result must be rewritten to the CURRENT operation ID, got %s want %s", op.ResultJSON, wantRewritten)
	}
	if n := legacyCount(t, store, histID2); n != 0 {
		t.Fatalf("historical succeeded quarantine row must be deleted, got %d", n)
	}

	// 5. CONFLICT under the CURRENT identity: stored hash != reqHash.
	seed("cur-conflict", "pending", "", feedSignerTestHash("different"))
	if _, err := store.AdoptLegacyFeedSignerOperation(ctx, "cur-conflict", reg.ID, topic, ref, feedSignerTestHash("other"), nil); !errors.Is(err, errFeedSignerLegacyConflict) {
		t.Fatalf("current differing hash must conflict, got %v", err)
	}
	if n := legacyCount(t, store, "cur-conflict"); n != 1 {
		t.Fatalf("current conflict row must stay quarantined, got %d", n)
	}

	// 6. CONFLICT under the HISTORICAL identity: stored hash != historical hash.
	//    The caller's operation ID is FRESH so the active-row short-circuit does
	//    not hide the conflict.
	seed(histID, "pending", "", feedSignerTestHash("not-the-m9-hash"))
	if _, err := store.AdoptLegacyFeedSignerOperation(ctx, "hist-conflict-caller", reg.ID, topic, ref, feedSignerTestHash("caller-hash"), []LegacyOperationCandidate{{OperationID: histID, RequestHash: histHash}}); !errors.Is(err, errFeedSignerLegacyConflict) {
		t.Fatalf("historical differing hash must conflict, got %v", err)
	}
	if n := legacyCount(t, store, histID); n != 1 {
		t.Fatalf("historical conflict row must stay quarantined, got %d", n)
	}

	// 7. A CURRENT-ID row carrying the OLD (m9) hash is incoherent: its claimed
	//    identity (current) demands the NEW hash, so it is a CONFLICT, never
	//    adopted (the round-3 "m9 hash over the current request" behavior).
	seed("legacy-hash-current-id", "pending", "", m9HistoricalRequestHash(func() publish.FeedCommitRequest { r := req; r.OperationID = "legacy-hash-current-id"; return r }()))
	_, err = store.AdoptLegacyFeedSignerOperation(ctx, "legacy-hash-current-id", reg.ID, topic, ref, reqHash, nil)
	if !errors.Is(err, errFeedSignerLegacyConflict) {
		t.Fatalf("current-ID row with old hash must conflict (coherent identity check), got %v", err)
	}
	if n := legacyCount(t, store, "legacy-hash-current-id"); n != 1 {
		t.Fatalf("incoherent row must stay quarantined, got %d", n)
	}

	// 8. Malformed succeeded legacy result -> fail closed, stays quarantined.
	seed("leg-mal", "succeeded", `{"operationID":"leg-mal","feed":"NOT_A_FEED","reference":"bad"}`, feedSignerTestHash("mal"))
	if _, err := store.AdoptLegacyFeedSignerOperation(ctx, "leg-mal", reg.ID, topic, ref, feedSignerTestHash("mal"), nil); !errors.Is(err, errFeedSignerLegacyMalformed) {
		t.Fatalf("malformed legacy succeeded result must fail closed, got %v", err)
	}
	if n := legacyCount(t, store, "leg-mal"); n != 1 {
		t.Fatalf("malformed legacy row must stay quarantined, got %d", n)
	}

	// 9. AMBIGUITY: TWO distinct valid candidates (one current, one historical)
	//    -> fail closed, neither adopted, both stay quarantined. The caller's
	//    operation ID is a FRESH id (no active row yet) so both candidates are
	//    actually reachable.
	dualCur := `{"operationID":"dual-cur","feed":"` + topic + `","reference":"` + ref + `"}`
	dualCurHash := NormalizeFeedCommitHash(func() publish.FeedCommitRequest { r := req; r.OperationID = "dual-cur"; return r }())
	seed("dual-cur", "succeeded", dualCur, dualCurHash)
	dualHistID := legacyComputeOperationID(reg.ID, req.Owner, "dualtagrepo", "v2", "sha256:"+strings.Repeat("b", 64), req.ExpectedGeneration)
	dualHistHash := legacyFeedCommitHashFor(dualHistID, req)
	dualHistResult := `{"operationID":"` + dualHistID + `","feed":"` + topic + `","reference":"` + ref + `"}`
	seed(dualHistID, "succeeded", dualHistResult, dualHistHash)
	if _, err := store.AdoptLegacyFeedSignerOperation(ctx, "dual-cur", reg.ID, topic, ref, dualCurHash, []LegacyOperationCandidate{{OperationID: dualHistID, RequestHash: dualHistHash}}); !errors.Is(err, errFeedSignerLegacyAmbiguous) {
		t.Fatalf("two valid candidates must be an ambiguity that fails closed, got %v", err)
	}
	if n := legacyCount(t, store, "dual-cur"); n != 1 {
		t.Fatalf("ambiguous current row must stay quarantined, got %d", n)
	}
	if n := legacyCount(t, store, dualHistID); n != 1 {
		t.Fatalf("ambiguous historical row must stay quarantined, got %d", n)
	}
}

func legacyCount(t *testing.T, store *Store, opID string) int {
	t.Helper()
	var n int
	if err := store.DB.QueryRowContext(context.Background(),
		`select count(*) from feed_signer_operations_legacy where operation_id=?`, opID).Scan(&n); err != nil {
		t.Fatalf("count legacy: %v", err)
	}
	return n
}

// TestAdoptLegacyFeedSignerOperationMultiTagCandidates drives the migration-9
// quarantine adoption gate with a BOUNDED MULTI-CANDIDATE legacy identity set —
// the form the signer derives from a multi-tag target repo-state document (one
// {historical operation ID, historical request hash} per valid tag entry). The
// quarantined row's own primary key identifies which candidate was the old
// publication:
//
//   - two legacy candidates with ONE existing historical row -> that row adopts
//     (pending promoted under the current ID/hash; succeeded promoted with the
//     result rewritten to the current ID);
//   - the same manifest digest under TWO tags, one existing row -> that row
//     adopts;
//   - TAG OVERWRITE: a quarantine row keyed by an OLDER publication's
//     (tag, digest) that is NOT in the derived candidate set is never adopted;
//   - TWO existing rows that both match derived candidates (two legacy tags) ->
//     ambiguity, all rows retained;
//   - one VALID matching row PLUS one hash-mismatched (conflicting) row ->
//     CONFLICT with ALL rows retained — a conflicting candidate is never
//     ignored merely because another matches;
//   - a duplicate derived ID and an over-cap candidate list fail closed;
//   - zero rows -> no-op (reserve current normally).
func TestAdoptLegacyFeedSignerOperationMultiTagCandidates(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	ref := strings.Repeat("ab", 32)
	nowNs := timeToNanos(time.Now().UTC())
	seed := func(opID, state, result string, hash [32]byte) {
		t.Helper()
		if _, err := store.DB.ExecContext(ctx, `insert into feed_signer_operations_legacy
			(operation_id, request_hash, state, result_json, created_at, updated_at)
			values (?, ?, ?, ?, ?, ?)`, opID, hash[:], state, sql.NullString{String: result, Valid: state == "succeeded"}, nowNs, nowNs); err != nil {
			t.Fatalf("seed legacy %s: %v", opID, err)
		}
	}
	// One concrete logical publication: caller sends the CURRENT operation ID;
	// the target doc carries multiple tags, so multiple historical identities
	// are derived. req.Owner is supplied raw (as the m9 identity consumed it).
	req := publish.FeedCommitRequest{
		OperationID:        "current-multi",
		RegistryID:         reg.ID,
		Owner:              "0x" + testFeedOwner,
		Topic:              topic,
		Reference:          ref,
		BatchID:            "batch-1",
		ExpectedGeneration: 4,
	}
	reqHash := NormalizeFeedCommitHash(req)
	hist := func(tag, digest string) LegacyOperationCandidate {
		t.Helper()
		id := legacyComputeOperationID(reg.ID, req.Owner, "repo1", tag, digest, req.ExpectedGeneration)
		return LegacyOperationCandidate{OperationID: id, RequestHash: legacyFeedCommitHashFor(id, req)}
	}
	digA := "sha256:" + strings.Repeat("a", 64)
	digB := "sha256:" + strings.Repeat("b", 64)

	t.Run("two-candidates-one-pending-row-adopts", func(t *testing.T) {
		c1, c2 := hist("latest", digA), hist("v2", digB)
		seed(c1.OperationID, "pending", "", c1.RequestHash)
		registerPublicationFence(t, store, "multi-pending", reg.ID)
		adopted, err := store.AdoptLegacyFeedSignerOperation(ctx, "multi-pending", reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{c1, c2})
		if err != nil || !adopted {
			t.Fatalf("multi-tag pending adoption: adopted=%v err=%v", adopted, err)
		}
		op, err := store.GetFeedSignerOperation(ctx, "multi-pending")
		if err != nil || op.State != FeedSignerOpPending || op.RequestHash != reqHash || op.RegistryID != reg.ID || op.Topic != topic {
			t.Fatalf("adopted multi-tag pending row malformed: %+v err=%v", op, err)
		}
		if n := legacyCount(t, store, c1.OperationID); n != 0 {
			t.Fatalf("adopted multi-tag pending row must be deleted, got %d", n)
		}
		if _, err := store.DB.ExecContext(ctx, `delete from feed_signer_operations where operation_id='multi-pending'`); err != nil {
			t.Fatalf("reset active: %v", err)
		}
	})
	t.Run("two-candidates-one-succeeded-row-adopts", func(t *testing.T) {
		c1, c2 := hist("latest", digA), hist("v2", digB)
		result := `{"operationID":"` + c1.OperationID + `","feed":"` + topic + `","reference":"` + ref + `"}`
		seed(c1.OperationID, "succeeded", result, c1.RequestHash)
		registerPublicationFence(t, store, "multi-succeeded", reg.ID)
		adopted, err := store.AdoptLegacyFeedSignerOperation(ctx, "multi-succeeded", reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{c1, c2})
		if err != nil || !adopted {
			t.Fatalf("multi-tag succeeded adoption: adopted=%v err=%v", adopted, err)
		}
		op, err := store.GetFeedSignerOperation(ctx, "multi-succeeded")
		if err != nil || op.State != FeedSignerOpSucceeded {
			t.Fatalf("adopted multi-tag succeeded row malformed: %+v err=%v", op, err)
		}
		want := `{"operationID":"multi-succeeded","feed":"` + topic + `","reference":"` + ref + `"}`
		if string(op.ResultJSON) != want {
			t.Fatalf("succeeded result must be rewritten to the CURRENT id, got %s want %s", op.ResultJSON, want)
		}
		if n := legacyCount(t, store, c1.OperationID); n != 0 {
			t.Fatalf("adopted quarantine row must be deleted, got %d", n)
		}
	})
	t.Run("same-digest-two-tags-one-row-adopts", func(t *testing.T) {
		// The SAME manifest digest under two tags: both historical identities
		// are derived; only the "aliased" tag's row exists in quarantine.
		cA, cB := hist("alias-a", digB), hist("alias-b", digB)
		if cA.OperationID == cB.OperationID {
			t.Fatal("test requires distinct historical IDs for distinct tags")
		}
		seed(cA.OperationID, "pending", "", cA.RequestHash)
		registerPublicationFence(t, store, "same-digest", reg.ID)
		adopted, err := store.AdoptLegacyFeedSignerOperation(ctx, "same-digest", reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{cA, cB})
		if err != nil || !adopted {
			t.Fatalf("same-digest multi-tag adoption: adopted=%v err=%v", adopted, err)
		}
		if n := legacyCount(t, store, cA.OperationID); n != 0 {
			t.Fatalf("adopted quarantine row must be deleted, got %d", n)
		}
	})
	t.Run("tag-overwrite-old-row-not-matched", func(t *testing.T) {
		// The target doc carries latest -> digA (the value AFTER the overwrite).
		// A quarantine row from an OLDER publication keyed by latest -> digB is
		// NOT in the derived candidate set: it must never be adopted or deleted.
		c := hist("latest", digA)
		old := hist("latest", digB)
		seed(old.OperationID, "succeeded",
			`{"operationID":"`+old.OperationID+`","feed":"`+topic+`","reference":"`+ref+`"}`, old.RequestHash)
		adopted, err := store.AdoptLegacyFeedSignerOperation(ctx, "tag-overwrite", reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{c})
		if err != nil || adopted {
			t.Fatalf("old overwritten row must NOT adopt: adopted=%v err=%v", adopted, err)
		}
		if n := legacyCount(t, store, old.OperationID); n != 1 {
			t.Fatalf("overwritten row must stay quarantined untouched, got %d", n)
		}
	})
	t.Run("two-legacy-rows-ambiguity-preserves-all", func(t *testing.T) {
		c1, c2 := hist("t-ambig-a", digA), hist("t-ambig-b", digB)
		r1 := `{"operationID":"` + c1.OperationID + `","feed":"` + topic + `","reference":"` + ref + `"}`
		r2 := `{"operationID":"` + c2.OperationID + `","feed":"` + topic + `","reference":"` + ref + `"}`
		seed(c1.OperationID, "succeeded", r1, c1.RequestHash)
		seed(c2.OperationID, "succeeded", r2, c2.RequestHash)
		if _, err := store.AdoptLegacyFeedSignerOperation(ctx, "two-row-ambig", reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{c1, c2}); !errors.Is(err, errFeedSignerLegacyAmbiguous) {
			t.Fatalf("two matching legacy rows must be an ambiguity, got %v", err)
		}
		if legacyCount(t, store, c1.OperationID) != 1 || legacyCount(t, store, c2.OperationID) != 1 {
			t.Fatal("ambiguous rows must ALL stay quarantined")
		}
	})
	t.Run("valid-plus-conflict-never-ignored", func(t *testing.T) {
		// One row matches its candidate EXACTLY; the OTHER row's stored hash
		// differs from its candidate's historical hash. The adoption must fail
		// CLOSED as a conflict and retain BOTH rows — a conflicting candidate is
		// never ignored merely because another one matches.
		c1, c2 := hist("t-conf-a", digA), hist("t-conf-b", digB)
		seed(c1.OperationID, "pending", "", c1.RequestHash)
		seed(c2.OperationID, "pending", "", feedSignerTestHash("corrupted-hash"))
		if _, err := store.AdoptLegacyFeedSignerOperation(ctx, "valid-plus-conflict", reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{c1, c2}); !errors.Is(err, errFeedSignerLegacyConflict) {
			t.Fatalf("conflicting candidate must fail the whole adoption, got %v", err)
		}
		if legacyCount(t, store, c1.OperationID) != 1 || legacyCount(t, store, c2.OperationID) != 1 {
			t.Fatal("conflict must retain EVERY candidate row")
		}
	})
	t.Run("duplicate-derived-id-rejected", func(t *testing.T) {
		c1 := hist("latest", digA)
		c2 := c1
		c2.RequestHash = feedSignerTestHash("different")
		seed(c1.OperationID, "pending", "", c1.RequestHash)
		if _, err := store.AdoptLegacyFeedSignerOperation(ctx, "dup-id", reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{c1, c2}); !errors.Is(err, errFeedSignerLegacyMalformed) {
			t.Fatalf("duplicate derived ID must fail closed deterministically, got %v", err)
		}
		if n := legacyCount(t, store, c1.OperationID); n != 1 {
			t.Fatalf("duplicate-ID rejection must retain the row, got %d", n)
		}
	})
	t.Run("candidate-cap-fails-closed", func(t *testing.T) {
		cands := make([]LegacyOperationCandidate, feedSignerLegacyMaxCandidates+1)
		for i := range cands {
			cands[i] = LegacyOperationCandidate{OperationID: fmt.Sprintf("id-%d", i), RequestHash: feedSignerTestHash(fmt.Sprintf("h-%d", i))}
		}
		if _, err := store.AdoptLegacyFeedSignerOperation(ctx, "cap-op", reg.ID, topic, ref, reqHash, cands); !errors.Is(err, errFeedSignerLegacyMalformed) {
			t.Fatalf("over-cap candidate list must fail closed, got %v", err)
		}
	})
	t.Run("no-rows-no-op", func(t *testing.T) {
		adopted, err := store.AdoptLegacyFeedSignerOperation(ctx, "no-rows", reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{hist("t-none-x", digA), hist("t-none-y", digB)})
		if err != nil || adopted {
			t.Fatalf("zero candidate rows must be a no-op: adopted=%v err=%v", adopted, err)
		}
	})
}

// TestAdoptLegacyFeedSignerOperationTwoStoresRace proves cross-Store
// serialization: TWO independent Store instances (separate connection pools over
// ONE on-disk database) race to adopt the SAME quarantined migration-9 row.
// withWriteTx serializes the whole read/insert/delete under BEGIN IMMEDIATE with
// bounded busy-retry, so exactly ONE adopter can succeed: the loser either
// starts after the winner commits and short-circuits on the new ACTIVE row
// (adopted=false, no error), and the quarantine row is deleted exactly once —
// no evidence is ever lost or double-deleted. A retry by the loser then
// resolves through the normal idempotent path.
func TestAdoptLegacyFeedSignerOperationTwoStoresRace(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "adopt-race.db")
	open := func() *Store {
		t.Helper()
		s, err := OpenSQLite(dbPath)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		if _, err := s.DB.ExecContext(ctx, `pragma busy_timeout = 10000`); err != nil {
			t.Fatalf("busy_timeout: %v", err)
		}
		t.Cleanup(func() { _ = s.DB.Close() })
		return s
	}
	storeA, storeB := open(), open()

	owner, err := storeA.CreateUser(ctx, "racer@example.com", "hash")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	reg, err := storeA.CreateProvisionedRegistry(ctx, Registry{
		Slug: "racer", Host: "racer.test", ENSName: "", OwnerUserID: owner.ID,
		FeedOwnerAddress: testFeedOwner, DefaultStampBatchID: "batch-1", AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	if err := storeA.MarkRegistryReady(ctx, reg.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
	topic := spec.RepoStateFeedRef(testFeedOwner, testRepo)
	ref := strings.Repeat("ab", 32)
	req := publish.FeedCommitRequest{
		OperationID: "race-op", RegistryID: reg.ID, Owner: "0x" + testFeedOwner,
		Topic: topic, Reference: ref, BatchID: "batch-1", ExpectedGeneration: 4,
	}
	reqHash := NormalizeFeedCommitHash(req)
	histID := legacyComputeOperationID(reg.ID, req.Owner, "repo1", "latest", "sha256:"+strings.Repeat("a", 64), req.ExpectedGeneration)
	histHash := legacyFeedCommitHashFor(histID, req)
	nowNs := timeToNanos(time.Now().UTC())
	if _, err := storeA.DB.ExecContext(ctx, `insert into feed_signer_operations_legacy
		(operation_id, request_hash, state, result_json, created_at, updated_at)
		values (?, ?, 'pending', null, ?, ?)`, histID, histHash[:], nowNs, nowNs); err != nil {
		t.Fatalf("seed quarantine row: %v", err)
	}
	registerPublicationFence(t, storeA, "race-op", reg.ID)

	const n = 2
	start := make(chan struct{})
	var wg sync.WaitGroup
	adopted := make([]bool, n)
	errs := make([]error, n)
	for i, s := range []*Store{storeA, storeB} {
		wg.Add(1)
		go func(i int, s *Store) {
			defer wg.Done()
			<-start
			adopted[i], errs[i] = s.AdoptLegacyFeedSignerOperation(ctx, "race-op", reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{{OperationID: histID, RequestHash: histHash}})
		}(i, s)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("racer %d: unexpected adoption error: %v", i, errs[i])
		}
		if adopted[i] {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("exactly ONE racer must adopt, got %d (adopted=%v)", wins, adopted)
	}
	// Evidence: quarantine row gone exactly once; active row carries the
	// current identity/hash.
	if n := legacyCount(t, storeA, histID); n != 0 {
		t.Fatalf("quarantine row must be deleted exactly once, got %d", n)
	}
	op, err := storeA.GetFeedSignerOperation(ctx, "race-op")
	if err != nil || op.State != FeedSignerOpPending || op.RequestHash != reqHash {
		t.Fatalf("active row malformed after race: %+v err=%v", op, err)
	}
	// A retry through the LOSER store resolves idempotently (no adoption, no
	// error): the active row now short-circuits the adoption.
	if adoptedRetry, err := storeB.AdoptLegacyFeedSignerOperation(ctx, "race-op", reg.ID, topic, ref, reqHash, []LegacyOperationCandidate{{OperationID: histID, RequestHash: histHash}}); err != nil || adoptedRetry {
		t.Fatalf("loser retry must short-circuit: adopted=%v err=%v", adoptedRetry, err)
	}
}

// TestFeedSignerResultCanonicalByteExactTriggers proves migration 12's
// corrected DB result-integrity triggers enforce BYTE-FOR-BYTE equality to the
// single canonical Go result layout on direct SQL. The old migration-11
// `json(NEW.result_json) = NEW.result_json` proof minifies but PRESERVES member
// order and spelling, so it ACCEPTED a reordered-members object, an escaped key
// spelling (operation\u0049D), and an escaped value spelling (feed:\/\/). The
// corrected trigger must reject all of those while accepting the genuine
// canonical layout, on BOTH the INSERT and UPDATE paths.
func TestFeedSignerResultCanonicalByteExactTriggers(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	ref := strings.Repeat("ab", 32)
	nowNs := timeToNanos(time.Now().UTC())

	ins := func(opID, result string) error {
		h := feedSignerTestHash(opID)
		_, err := db.ExecContext(ctx, `insert into feed_signer_operations
			(operation_id, registry_id, topic, request_hash, state, result_json,
			 claim_token, lease_until, attempts, created_at, updated_at)
			values (?, ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
			opID, reg.ID, topic, h[:], result, nowNs, nowNs)
		return err
	}
	upd := func(opID, result string) error {
		_, err := db.ExecContext(ctx, `update feed_signer_operations
			set state='succeeded', result_json=?, claim_token=null, lease_until=null
			where operation_id = ?`, result, opID)
		return err
	}

	canonical := `{"operationID":"ok-canon","feed":"` + topic + `","reference":"` + ref + `"}`
	ch := feedSignerTestHash("ok-canon")
	registerPublicationFence(t, store, "ok-canon", reg.ID)
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values ('ok-canon', ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
		reg.ID, topic, ch[:], canonical, nowNs, nowNs); err != nil {
		t.Fatalf("seed canonical row: %v", err)
	}
	// Canonical UPDATE accepted (byte-identical to Go's json.Marshal).
	if err := upd("ok-canon", canonical); err != nil {
		t.Fatalf("canonical update rejected: %v", err)
	}

	escapedFeed := `feed:\/\/` + strings.TrimPrefix(topic, "feed://")
	// Each byte-exact violation carries the OPERATION ID that makes every
	// semantic check pass, so ONLY the byte-exact equality clause can reject it.
	cases := []struct {
		name   string
		result func(opID string) string
	}{
		{"reordered-members", func(opID string) string {
			return `{"feed":"` + topic + `","operationID":"` + opID + `","reference":"` + ref + `"}`
		}},
		{"escaped-key", func(opID string) string {
			return `{"operation\u0049D":"` + opID + `","feed":"` + topic + `","reference":"` + ref + `"}`
		}},
		{"escaped-feed-value", func(opID string) string {
			return `{"operationID":"` + opID + `","feed":"` + escapedFeed + `","reference":"` + ref + `"}`
		}},
		{"whitespace", func(opID string) string {
			return `{ "operationID" : "` + opID + `", "feed" : "` + topic + `", "reference" : "` + ref + `" }`
		}},
		{"duplicate-key", func(opID string) string {
			return `{"operationID":"` + opID + `","feed":"` + topic + `","reference":"` + ref + `","operationID":"` + opID + `"}`
		}},
		{"extra-field", func(opID string) string {
			return `{"operationID":"` + opID + `","feed":"` + topic + `","reference":"` + ref + `","extra":1}`
		}},
		{"wrong-op-id", func(opID string) string {
			return `{"operationID":"DIFFERENT","feed":"` + topic + `","reference":"` + ref + `"}`
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/insert", func(t *testing.T) {
			opID := "x-" + tc.name
			if err := ins(opID, tc.result(opID)); err == nil {
				t.Fatal("expected INSERT trigger reject; got nil")
			}
		})
		t.Run(tc.name+"/update", func(t *testing.T) {
			if err := upd("ok-canon", tc.result("ok-canon")); err == nil {
				t.Fatal("expected UPDATE trigger reject; got nil")
			}
		})
	}
}

// TestMigration12RejectsNonCanonicalV11RowRollsBack proves migration 12's
// atomic hardening: a v11 database whose active succeeded row matches the loose
// v11 `json()<>` proof but is NOT byte-canonical (reordered members — which
// json() accepts) causes migration 12 to FAIL and roll back byte-identically:
// the version stays 11, the row is untouched, and the v11 trigger remains
// installed. No rewrite or deletion, ever.
func TestMigration12RejectsNonCanonicalV11RowRollsBack(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 11); err != nil {
		t.Fatalf("apply through v11: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	ref := strings.Repeat("ab", 32)
	nowNs := timeToNanos(time.Now().UTC())

	// A reordered-members succeeded result passes the v11 trigger (json()
	// preserves order) but violates the v12 BYTE-EXACT contract.
	reordered := `{"feed":"` + topic + `","operationID":"v11-reordered","reference":"` + ref + `"}`
	rh := feedSignerTestHash("v11-reordered")
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values ('v11-reordered', ?, ?, ?, 'succeeded', ?, null, null, 0, ?, ?)`,
		reg.ID, topic, rh[:], reordered, nowNs, nowNs); err != nil {
		t.Fatalf("v11 must ACCEPT a reordered-members succeeded row (the round-2 defect): %v", err)
	}

	if err := ApplyMigrations(ctx, db); err == nil {
		t.Fatal("migration 12 must fail when hardening encounters a non-canonical v11 row")
	}
	// Version stays 11; the row is byte-identical (total rollback).
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 11 {
		t.Fatalf("version must stay 11 on adversarial migration 12, got %d (err %v)", v, err)
	}
	var gotRes []byte
	if err := db.QueryRowContext(ctx, `select result_json from feed_signer_operations
		where operation_id='v11-reordered'`).Scan(&gotRes); err != nil {
		t.Fatalf("read row after rollback: %v", err)
	}
	if string(gotRes) != reordered {
		t.Fatalf("non-canonical row must be byte-identical after rollback: %s", gotRes)
	}
}
