package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

// feedSignerTestHash derives a deterministic [32]byte request hash for tests.
func feedSignerTestHash(seed string) [32]byte {
	return sha256.Sum256([]byte("feed-signer-test:" + seed))
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
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xsigner", DefaultStampBatchID: "batch-signer",
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
	if err != nil || v != 10 {
		t.Fatalf("expected schema version 10, got %d (err %v)", v, err)
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

// TestMigration10FailsClosedOnNonEmptyM9 proves migration 10 REFUSES to upgrade
// a database carrying migration-9 rows (the control-plane registry_id and
// canonical topic are not derivable from an m9 row, so carrying one forward
// would fabricate them). It fails atomically: version stays 9, the row is
// intact.
func TestMigration10FailsClosedOnNonEmptyM9(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	if err := applyMigrationsThrough(ctx, db, 9); err != nil {
		t.Fatalf("apply through 9: %v", err)
	}
	legacyHash := feedSignerTestHash("legacy")
	nowNs := timeToNanos(time.Now().UTC())
	if _, err := db.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, request_hash, state, result_json, created_at, updated_at)
		values (?, ?, 'pending', null, ?, ?)`, "m9-legacy-op", legacyHash[:], nowNs, nowNs); err != nil {
		t.Fatalf("seed m9 row: %v", err)
	}
	if err := applyMigrationsThrough(ctx, db, 10); err == nil {
		t.Fatal("expected migration 10 to fail closed on a non-empty migration-9 table")
	}
	if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 9 {
		t.Fatalf("expected version to stay 9, got %d (err %v)", v, err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `select count(*) from feed_signer_operations`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected the m9 legacy row to survive the failed upgrade, got %d rows", n)
	}
}

// TestFeedSignerOperationReserveClaimCompleteLifecycle is the happy path:
// reserve -> claim (won) -> complete -> succeeded with a claim-free canonical
// result.
func TestFeedSignerOperationReserveClaimCompleteLifecycle(t *testing.T) {
	store := newProvisioningStore(t)
	reg, topic := seedFeedSignerRegistry(t, store)
	ctx := context.Background()
	reqHash := feedSignerTestHash("lifecycle")

	op, err := store.ReserveFeedSignerOperation(ctx, "op-lifecycle", reg.ID, topic, reqHash)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if op.State != FeedSignerOpPending || op.RegistryID != reg.ID || op.Topic != topic ||
		op.ResultJSON != nil || op.ClaimToken != nil || op.LeaseUntil != nil {
		t.Fatalf("pending operation malformed after reserve: %+v", op)
	}

	token := newClaimToken()
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
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-release", reg.ID, topic, reqHash); err != nil {
		t.Fatal(err)
	}
	token := newClaimToken()
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
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-takeover", reg.ID, topic, reqHash); err != nil {
		t.Fatal(err)
	}
	oldToken := newClaimToken()
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-takeover", reqHash, oldToken, time.Now().UTC().Add(-10*time.Minute)); err != nil || !won {
		t.Fatalf("initial claim: won=%v err=%v", won, err)
	}
	newToken := newClaimToken()
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
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-A", reg.ID, topic, hashA); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-B", reg.ID, topic, hashB); err != nil {
		t.Fatal(err)
	}
	tokenA := newClaimToken()
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-A", hashA, tokenA, time.Now().UTC().Add(time.Hour)); err != nil || !won {
		t.Fatalf("claim op-A: won=%v err=%v", won, err)
	}
	// op-B on the SAME registry+topic cannot claim while op-A holds the slot.
	if won, err := store.ClaimFeedSignerOperation(ctx, "op-B", hashB, newClaimToken(), time.Now().UTC().Add(time.Hour)); err == nil && won {
		t.Fatal("expected distinct-op claim on the same repo feed to be refused")
	}
	// op-A completes and frees the slot.
	resultA := []byte(`{"operationID":"op-A","feed":"` + topic + `","reference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if err := store.CompleteFeedSignerOperation(ctx, "op-A", hashA, tokenA, resultA); err != nil {
		t.Fatalf("complete op-A: %v", err)
	}
	// op-B can now claim and complete.
	tokenB := newClaimToken()
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
	if _, err := store.ReserveFeedSignerOperation(ctx, "op-idem", reg.ID, topic, reqHash); err != nil {
		t.Fatal(err)
	}
	token := newClaimToken()
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
	// is EXACT, not over-restrictive.
	goodHash := feedSignerTestHash("good")
	if _, err := store.DB.ExecContext(ctx, sqlPrefix+
		`('op-adv-good', ?, ?, ?, 'succeeded', '`+validResult+`', null, null, 0, ?, ?)`,
		reg.ID, topic, goodHash[:], nowNs, nowNs); err != nil {
		t.Fatalf("well-formed succeeded row rejected: %v", err)
	}

	// An extra field is allowed by SQL but rejected by the strict Go decoder
	// (which is covered by the signer strict-decode tests).
}
